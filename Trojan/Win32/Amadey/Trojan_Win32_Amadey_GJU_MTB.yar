
rule Trojan_Win32_Amadey_GJU_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 43 ca 03 c1 3b f0 0f 84 90 01 04 8a 04 33 8d 4d dc 32 06 88 45 fb 8d 45 fb 90 00 } //10
		$a_01_1 = {41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //1 Amadey\Release\Amadey.pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}