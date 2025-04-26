
rule Trojan_Win32_GuLoader_RSG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {63 68 61 72 70 69 65 74 5c 53 75 6d 6d 65 72 74 69 64 65 32 34 35 5c 41 6e 73 6b 75 65 6c 69 67 74 } //1 charpiet\Summertide245\Anskueligt
		$a_81_1 = {6d 6f 74 61 74 6f 72 79 5c 47 75 64 6d 64 72 65 6e 65 5c 6b 72 65 6d 61 74 6f 72 69 65 72 } //1 motatory\Gudmdrene\krematorier
		$a_81_2 = {25 49 6e 65 66 66 65 6b 74 69 76 69 74 65 74 65 72 6e 65 34 30 25 5c 62 65 6a 61 70 65 5c 4c 75 6c 6c 65 74 32 31 30 } //1 %Ineffektiviteterne40%\bejape\Lullet210
		$a_81_3 = {25 54 72 61 62 75 63 6f 73 25 5c 70 72 6f 74 65 73 74 61 74 69 6f 6e 73 5c 75 6e 66 69 65 6e 64 6c 69 6b 65 } //1 %Trabucos%\protestations\unfiendlike
		$a_81_4 = {5c 66 75 6e 6b 65 5c 42 65 66 6f 6c 6b 6e 69 6e 67 73 74 74 68 65 64 65 72 73 37 35 2e 6b 61 6c } //1 \funke\Befolkningsttheders75.kal
		$a_81_5 = {5c 53 75 67 65 73 6b 69 76 65 31 34 30 2e 73 6d 75 } //1 \Sugeskive140.smu
		$a_81_6 = {67 65 6e 66 72 65 6d 73 74 69 6c 6c 65 73 20 64 6d 72 69 6e 67 65 72 2e 65 78 65 } //1 genfremstilles dmringer.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}