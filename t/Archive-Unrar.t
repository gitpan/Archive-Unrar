use Test::More tests=>1;
use Devel::CheckOS qw (os_is);

ok (OStest()==1,'OS compatibility test');

sub OStest {
return 1 if os_is('MicrosoftWindows'); 
}
