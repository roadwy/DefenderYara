
rule TrojanDownloader_Win64_Malgent_NITB_MTB{
	meta:
		description = "TrojanDownloader:Win64/Malgent.NITB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 20 48 8d 6c 24 ?? 48 89 d6 48 89 cf 48 8d 0d ?? ?? ?? 00 ff 15 d1 5d 06 00 48 85 c0 74 20 48 8d 15 ?? ?? ?? 00 48 89 c1 ff 15 c4 5d 06 00 48 85 c0 4c 8d 05 ?? ?? ?? 00 4c 0f 45 c0 eb 07 4c 8d 05 ?? ?? ?? 00 4c 89 05 ?? ?? ?? ?? 48 89 f9 48 89 f2 48 83 c4 20 } //2
		$a_01_1 = {63 6d 37 34 33 33 36 2e 74 77 31 2e 72 75 2f 63 61 6c 63 2e 65 78 65 63 61 6c 63 2e 65 78 65 73 72 63 } //3 cm74336.tw1.ru/calc.execalc.exesrc
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}