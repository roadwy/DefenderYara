
rule Backdoor_Linux_Mirai_GS_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {00 95 04 20 80 0f 00 00 00 60 45 20 00 0c 00 b5 94 ?? 0f 85 42 20 40 00 0f a5 ?? ?? f0 a5 40 25 00 1e 2f 27 0c 10 15 0f 92 10 8a 20 81 18 81 d9 01 da 00 db 6f 22 3f 00 } //1
		$a_02_1 = {0b 20 00 a4 ae 01 04 00 04 26 80 1f 00 00 03 80 01 68 21 6f 04 79 99 09 21 80 04 1d 00 14 06 26 c0 73 00 00 00 04 cb 78 ?? ?? 04 27 8f 1f 00 00 00 80 e5 7e 44 26 c0 10 20 95 01 68 47 20 c0 00 14 68 04 21 81 0f 00 00 00 20 04 26 8e 1f ff ff 00 84 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}