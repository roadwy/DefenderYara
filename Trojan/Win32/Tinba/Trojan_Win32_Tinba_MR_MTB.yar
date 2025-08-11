
rule Trojan_Win32_Tinba_MR_MTB{
	meta:
		description = "Trojan:Win32/Tinba.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 15 3d 61 42 00 0f af ca 0f af 0d 28 61 42 00 a0 36 61 42 00 02 c1 } //5
		$a_01_1 = {0f be 55 d0 81 c2 94 00 00 00 8a 45 8c 2a c2 88 45 8c 8b 4d 98 0f af 4d a0 } //10
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*10) >=15
 
}