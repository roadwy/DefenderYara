
rule Trojan_Win32_Barys_CCJZ_MTB{
	meta:
		description = "Trojan:Win32/Barys.CCJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 95 f0 f3 ff ff 8b 42 0c 83 e0 10 09 c0 75 ?? 8b 8d f0 f3 ff ff 51 68 00 04 00 00 6a 01 8d 95 f4 f3 ff ff 52 e8 ?? ?? ?? ?? 83 c4 10 89 85 f4 f7 ff ff 8b 85 f8 f7 ff ff 50 8b 8d f4 f7 ff ff 51 6a 01 8d 95 f4 f3 ff ff 52 e8 ?? ?? ?? ?? 83 c4 10 eb } //2
		$a_03_1 = {8b 85 e4 f7 ff ff 50 8b 8d f0 f7 ff ff 51 ff 15 ?? ?? ?? ?? f7 d8 1b c0 40 88 85 f8 f7 ff ff 83 bd fc f7 ff ff 14 7e ?? c7 85 fc f7 ff ff 00 00 00 00 6a 02 ff 15 ?? ?? ?? ?? 8b 95 fc f7 ff ff 83 c2 01 89 95 fc f7 ff ff e9 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}