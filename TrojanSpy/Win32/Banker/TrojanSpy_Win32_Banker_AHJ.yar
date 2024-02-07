
rule TrojanSpy_Win32_Banker_AHJ{
	meta:
		description = "TrojanSpy:Win32/Banker.AHJ,SIGNATURE_TYPE_PEHSTR_EXT,ffffffae 01 ffffffa4 01 09 00 00 2c 01 "
		
	strings :
		$a_01_0 = {43 23 3a 25 5c 2a 42 23 61 25 6e 25 63 23 6f 2a 42 2a 72 2a 61 23 73 2a 69 25 6c 23 } //64 00  C#:%\*B#a%n%c#o*B*r*a#s*i%l#
		$a_01_1 = {69 23 6e 2a 66 2a 65 25 63 40 74 23 2f 40 69 6e 66 34 2a 2f 2a 69 2a 6e 2a 64 25 65 25 78 25 2e 25 70 25 68 25 70 } //64 00  i#n*f*e%c@t#/@inf4*/*i*n*d%e%x%.%p%h%p
		$a_01_2 = {25 73 25 68 23 75 25 74 23 64 25 6f 25 77 25 6e 2a 20 25 2d 40 66 25 20 40 2d 23 72 40 } //0a 00  %s%h#u%t#d%o%w%n* %-@f% @-#r@
		$a_01_3 = {2f 23 2f 23 63 25 64 2a 78 2a 32 25 30 2a 31 40 35 23 2e 40 74 2a 68 25 61 2a 69 23 65 23 61 23 73 23 79 40 64 25 6e 40 73 40 2e 25 63 23 6f 23 6d 40 2f 2a 6d } //0a 00  /#/#c%d*x*2%0*1@5#.@t*h%a*i#e#a#s#y@d%n@s@.%c#o#m@/*m
		$a_01_4 = {63 23 6d 2a 64 40 20 2a 2f 2a 63 25 20 23 72 23 6d 2a 64 2a 69 25 72 23 20 2a 2f 25 73 25 20 40 2f 25 71 25 } //0a 00  c#m*d@ */*c% #r#m*d*i%r# */%s% @/%q%
		$a_01_5 = {53 4c 77 6b 64 4b 7a 6a 58 5f 35 74 6a 50 46 36 65 4a 79 70 57 36 75 6d 53 49 71 67 4d 43 } //0a 00  SLwkdKzjX_5tjPF6eJypW6umSIqgMC
		$a_01_6 = {77 69 6e 6b 61 76 2e 63 70 6c } //0a 00  winkav.cpl
		$a_01_7 = {70 2a 72 25 6f 23 63 2a 65 23 73 2a 73 2a 78 2a 78 23 78 25 32 25 } //0a 00  p*r%o#c*e#s*s*x*x#x%2%
		$a_01_8 = {69 6e 69 74 2e 76 72 78 00 } //00 00 
	condition:
		any of ($a_*)
 
}