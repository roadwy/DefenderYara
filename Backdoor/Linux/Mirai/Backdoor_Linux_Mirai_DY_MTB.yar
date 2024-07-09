
rule Backdoor_Linux_Mirai_DY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 25 20 89 00 25 50 45 01 25 30 cb 00 40 6b 0d 00 00 73 0e 00 c0 62 0c 00 80 7a 0f 00 80 00 b0 af 34 00 a3 af 30 00 a4 af 2c 00 aa af 28 00 a6 af 25 a8 e8 00 70 00 ad af 74 00 ae af 78 00 ac af 7c 00 af af } //1
		$a_03_1 = {06 00 1c 3c ?? ?? 9c 27 21 e0 99 03 e0 ff bd 27 10 00 bc af 1c 00 bf af 18 00 bc af 01 00 11 04 00 00 00 00 06 00 1c 3c ?? ?? 9c 27 21 e0 9f 03 20 80 99 8f 00 00 00 00 dc 01 39 27 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 00 00 01 00 11 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}