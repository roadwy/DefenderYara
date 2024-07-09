
rule Trojan_BAT_Injuke_SRP_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {9a 2b 4b 06 09 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 17 58 16 2d fb 16 2d f8 0c 08 07 8e 69 32 dd 06 2a 73 1f 00 00 0a 38 a3 ff ff ff 28 ?? ?? ?? 06 38 a2 ff ff ff 6f ?? ?? ?? 0a 38 9d ff ff ff 0a } //5
		$a_01_1 = {2f 00 31 00 34 00 37 00 2e 00 31 00 38 00 32 00 2e 00 31 00 39 00 32 00 2e 00 38 00 35 00 2f 00 63 00 6f 00 6d 00 6d 00 6f 00 6e 00 5f 00 4a 00 6a 00 68 00 6c 00 79 00 78 00 6c 00 64 00 2e 00 70 00 6e 00 67 00 } //2 /147.182.192.85/common_Jjhlyxld.png
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}