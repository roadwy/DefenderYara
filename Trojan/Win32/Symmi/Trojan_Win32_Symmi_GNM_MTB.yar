
rule Trojan_Win32_Symmi_GNM_MTB{
	meta:
		description = "Trojan:Win32/Symmi.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 51 bc 24 56 60 30 3c bc 41 b3 ff c3 } //10
		$a_01_1 = {01 31 08 5f 0f 09 63 30 1d 81 16 c3 df 37 30 34 36 2b 4e 82 ed 88 b1 } //10
		$a_01_2 = {6f 72 27 36 6c 61 73 73 20 48 69 65 72 4a 79 6f } //1 or'6lass HierJyo
		$a_01_3 = {72 76 79 38 53 69 7a 65 6f 66 52 65 73 6f 75 72 63 4c 6f } //1 rvy8SizeofResourcLo
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}