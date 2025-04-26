
rule Trojan_BAT_FormBook_MBXU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 2d 32 63 62 34 30 39 34 39 64 37 32 65 } //5 4-2cb40949d72e
		$a_01_1 = {72 65 64 69 73 74 2e 65 78 65 } //4 redist.exe
		$a_01_2 = {52 65 64 69 73 74 2e 42 61 63 6b 67 72 6f 75 6e 64 2e 70 6e 67 } //2 Redist.Background.png
		$a_01_3 = {24 35 37 34 63 38 63 62 37 } //1 $574c8cb7
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=12
 
}
rule Trojan_BAT_FormBook_MBXU_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 18 5d 2c ?? 02 06 07 6f ?? 00 00 0a 2b ?? 02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 12 ?? 28 ?? 00 00 0a 13 ?? 12 } //2
		$a_01_1 = {4c 00 6f 00 61 00 64 00 } //1 Load
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_MBXU_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {fe 04 16 fe 01 13 09 11 09 2c 2b 00 72 0f 06 00 70 } //1
		$a_01_1 = {72 70 67 41 73 73 69 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //2 rpgAssist.Properties.Resources.resource
		$a_01_2 = {54 00 5a 00 49 00 4e 00 4f 00 55 00 20 00 41 00 4e 00 54 00 4f 00 4e 00 49 00 41 00 } //3 TZINOU ANTONIA
		$a_01_3 = {33 00 49 00 2d 00 54 00 45 00 50 00 30 00 31 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=9
 
}