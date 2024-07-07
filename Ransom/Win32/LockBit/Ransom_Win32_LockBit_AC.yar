
rule Ransom_Win32_LockBit_AC{
	meta:
		description = "Ransom:Win32/LockBit.AC,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {8b 4d 08 8b 55 0c 90 01 01 81 31 90 01 04 f7 11 90 01 01 83 c1 04 4a 75 f1 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}