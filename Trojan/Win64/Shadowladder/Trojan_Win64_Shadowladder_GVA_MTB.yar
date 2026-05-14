
rule Trojan_Win64_Shadowladder_GVA_MTB{
	meta:
		description = "Trojan:Win64/Shadowladder.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 73 20 2d 77 20 2d 48 3d 77 69 6e 64 6f 77 73 67 75 69 20 2d 58 } //1 -s -w -H=windowsgui -X
		$a_02_1 = {3a 2f 2f 31 39 36 2e 32 35 31 2e 31 30 37 2e 31 30 39 2f [0-20] 2e 70 68 70 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}