
rule Trojan_Win32_CobaltStrike_PS_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //2 %c%c%c%c%c%c%c%c%cMSSE-%d-server
		$a_01_1 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00 c7 44 24 14 5c 00 00 00 c7 44 24 10 2e 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}