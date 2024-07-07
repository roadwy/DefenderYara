
rule Trojan_Win32_Redline_ASBG_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 80 34 1e 90 01 01 68 90 01 04 68 90 01 04 e8 90 01 04 50 e8 90 01 04 80 04 1e 90 01 01 68 90 01 04 68 90 01 04 e8 90 01 04 50 e8 90 01 04 80 04 1e 90 01 01 83 c4 30 46 3b f7 0f 90 00 } //1
		$a_01_1 = {48 61 6c 6c 6f 77 65 65 6e 20 42 65 61 73 74 73 } //1 Halloween Beasts
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}