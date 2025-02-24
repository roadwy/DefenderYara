
rule Trojan_BAT_Marsilia_NM_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 6f 55 00 00 0a 08 16 28 ?? ?? 00 0a 0d 06 72 ?? ?? 00 70 09 72 ?? ?? 00 70 6f ?? ?? 00 0a 5e 6f ?? ?? 00 0a 6f ?? ?? 00 0a 26 02 25 17 59 10 00 16 30 cb } //5
		$a_01_1 = {63 69 61 6f 2d 64 65 63 72 79 70 74 65 72 2e 65 78 65 } //1 ciao-decrypter.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Marsilia_NM_MTB_2{
	meta:
		description = "Trojan:BAT/Marsilia.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 61 69 4c 69 65 75 4a 58 } //2 TaiLieuJX
		$a_01_1 = {41 00 75 00 74 00 6f 00 4b 00 65 00 6f 00 58 00 65 00 2e 00 65 00 78 00 65 00 } //2 AutoKeoXe.exe
		$a_01_2 = {41 00 6e 00 74 00 69 00 56 00 6f 00 6c 00 61 00 6d 00 2e 00 69 00 6e 00 69 00 } //2 AntiVolam.ini
		$a_01_3 = {58 75 6e 67 42 61 47 69 61 6e 67 48 6f 2e 43 6f 6d } //1 XungBaGiangHo.Com
		$a_01_4 = {24 39 66 30 32 35 31 66 62 2d 62 37 34 39 2d 34 31 32 63 2d 39 32 38 61 2d 38 34 31 36 36 37 36 36 32 32 32 36 } //1 $9f0251fb-b749-412c-928a-841667662226
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}