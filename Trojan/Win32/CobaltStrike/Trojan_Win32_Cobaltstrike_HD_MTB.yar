
rule Trojan_Win32_Cobaltstrike_HD_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.HD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 90 02 0a 5c 43 6c 65 61 6e 55 70 5c 52 65 6c 65 61 73 65 5c 43 6c 65 61 6e 55 70 2e 70 64 62 90 00 } //10
		$a_01_1 = {43 6c 65 61 6e 55 70 2e 64 6c 6c 00 43 6c 65 61 6e 65 72 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}