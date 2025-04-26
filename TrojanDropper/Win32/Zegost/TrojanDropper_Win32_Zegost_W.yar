
rule TrojanDropper_Win32_Zegost_W{
	meta:
		description = "TrojanDropper:Win32/Zegost.W,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 ff d6 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 8b 75 fc 81 be ?? ?? 00 00 20 01 00 00 8d 46 10 50 74 0d 68 ?? ?? ?? ?? e8 ?? ?? ff ff 59 eb 05 } //2
		$a_01_1 = {5b 25 30 32 64 2f 25 30 32 64 2f 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 28 25 73 29 } //1 [%02d/%02d/%d %02d:%02d:%02d] (%s)
		$a_01_2 = {47 6c 6f 62 61 6c 5c 47 68 30 73 74 20 25 64 00 } //1 汇扯污䝜と瑳┠d
		$a_01_3 = {5c 5c 2e 5c 52 45 53 53 44 54 44 4f 53 00 } //1 屜尮䕒卓呄佄S
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}