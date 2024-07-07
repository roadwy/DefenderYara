
rule Trojan_Win32_CobaltStrike_RDB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 6d 69 6b 75 6e 79 30 75 61 72 65 78 6c 61 6f 68 65 69 32 69 } //1 1mikuny0uarexlaohei2i
		$a_01_1 = {46 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 8c 35 f0 fe ff ff 0f b6 d1 03 fa 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff 47 0f b6 84 3d f0 fe ff ff 88 84 35 f0 fe ff ff 88 8c 3d f0 fe ff ff 0f b6 84 35 f0 fe ff ff 03 c2 0f b6 c0 0f b6 84 05 f0 fe ff ff 30 84 1d e0 d6 ff ff 43 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}