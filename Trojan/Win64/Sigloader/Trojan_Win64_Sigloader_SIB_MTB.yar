
rule Trojan_Win64_Sigloader_SIB_MTB{
	meta:
		description = "Trojan:Win64/Sigloader.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {77 69 61 6b 79 30 30 90 01 01 5f 90 02 0a 2e 64 6c 6c 90 00 } //10
		$a_03_1 = {41 8b d7 48 8d 85 90 01 04 bf 90 01 04 8d 4a 90 01 01 89 08 d1 c2 48 83 c0 90 01 01 48 ff cf 75 90 01 01 89 b5 90 01 04 41 8b dd 4c 8d 95 90 01 04 bf 90 01 04 41 89 3a 83 fb 90 01 01 7c 90 01 01 4c 8d 85 90 01 04 4d 8d 4a 90 01 01 44 8b db 90 02 0a 41 8b 09 41 8b 00 8d 14 48 3b fa 0f 4c d7 8b fa 41 89 12 49 83 e9 90 01 01 49 83 c0 90 01 01 49 ff cb 75 90 01 01 ff c3 49 83 c2 90 01 01 83 fb 90 01 01 7e 90 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}