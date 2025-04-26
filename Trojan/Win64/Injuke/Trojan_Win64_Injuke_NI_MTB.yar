
rule Trojan_Win64_Injuke_NI_MTB{
	meta:
		description = "Trojan:Win64/Injuke.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 0f b7 df 44 0f af da 4d 63 db 49 63 fd 4d 01 cb 42 80 3c 1f 05 } //3
		$a_01_1 = {45 0f b7 df 44 0f af da 4d 63 db 42 80 7c 1e 06 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}