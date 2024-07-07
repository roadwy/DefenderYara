
rule Backdoor_Win32_Knockex_F{
	meta:
		description = "Backdoor:Win32/Knockex.F,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 60 ff 75 08 5f 8d 37 c0 cb 05 80 cf 5a 80 cf 02 80 c3 90 f7 db c0 eb 0a fe c7 ff 75 0c 5b ac 32 c3 aa fe c3 84 c0 75 f6 61 c9 c2 08 00 } //1
		$a_01_1 = {b2 8b 8b 70 6e 71 77 24 43 6f 75 6d 7e 6b 67 60 2d 5e 7d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}