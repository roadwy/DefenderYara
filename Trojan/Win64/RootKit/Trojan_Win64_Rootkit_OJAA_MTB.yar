
rule Trojan_Win64_Rootkit_OJAA_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.OJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b7 c2 48 8d 0c 80 41 8b 54 c9 2c 45 8b 44 c9 28 48 03 d3 41 8b 4c c9 24 48 03 ce e8 70 e3 ff ff 66 45 03 d4 66 44 3b 57 06 72 } //4
		$a_01_1 = {52 65 66 6c 65 63 74 69 76 65 44 6c 6c 4d 61 69 6e } //1 ReflectiveDllMain
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}