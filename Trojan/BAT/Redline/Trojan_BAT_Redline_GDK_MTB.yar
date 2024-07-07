
rule Trojan_BAT_Redline_GDK_MTB{
	meta:
		description = "Trojan:BAT/Redline.GDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6d 56 74 62 33 5a 6c 58 30 39 75 55 47 78 31 5a 32 6c 75 56 57 35 73 62 32 46 6b 61 57 35 6e 64 33 4a 70 64 47 56 55 62 30 4e 76 62 6e 4e 76 62 47 55 3d } //1 cmVtb3ZlX09uUGx1Z2luVW5sb2FkaW5nd3JpdGVUb0NvbnNvbGU=
		$a_80_1 = {41 6e 6e 61 43 6c 61 72 6b 4e 75 64 65 33 33 34 } //AnnaClarkNude334  1
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}