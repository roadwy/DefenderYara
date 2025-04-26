
rule Backdoor_Win32_Rukap_gen_B{
	meta:
		description = "Backdoor:Win32/Rukap.gen!B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 20 32 20 41 56 20 70 72 6f 67 72 61 6d 6d 65 72 73 20 66 72 6f 6d 20 49 6e 64 69 61 2e 20 59 6f 75 20 64 65 62 75 67 20 27 4d 6f 6f 6e 43 6c 69 63 6b 65 72 27 20 3a 29 } //1 Hello 2 AV programmers from India. You debug 'MoonClicker' :)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}