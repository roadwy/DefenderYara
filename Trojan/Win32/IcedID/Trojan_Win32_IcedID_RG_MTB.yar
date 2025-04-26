
rule Trojan_Win32_IcedID_RG_MTB{
	meta:
		description = "Trojan:Win32/IcedID.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 79 75 61 73 66 6e 69 75 68 61 79 67 73 62 64 68 6a 61 73 66 75 68 61 64 73 64 6a 6b 66 64 6b 6c 73 } //5 gyuasfniuhaygsbdhjasfuhadsdjkfdkls
		$a_01_1 = {30 62 61 35 34 64 35 37 39 61 62 35 63 64 36 64 } //5 0ba54d579ab5cd6d
		$a_01_2 = {39 35 31 64 36 30 35 64 32 36 66 39 61 33 35 33 } //5 951d605d26f9a353
		$a_01_3 = {47 65 74 43 6f 6e 73 6f 6c 65 53 63 72 65 65 6e 42 75 66 66 65 72 49 6e 66 6f } //1 GetConsoleScreenBufferInfo
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=16
 
}