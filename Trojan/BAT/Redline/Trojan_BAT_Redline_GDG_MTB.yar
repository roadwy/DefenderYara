
rule Trojan_BAT_Redline_GDG_MTB{
	meta:
		description = "Trojan:BAT/Redline.GDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 16 07 16 1f 10 28 ?? ?? ?? 0a 08 16 07 1f 0f 1f 10 28 ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 2a } //10
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}