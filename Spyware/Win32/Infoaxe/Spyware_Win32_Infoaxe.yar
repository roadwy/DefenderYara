
rule Spyware_Win32_Infoaxe{
	meta:
		description = "Spyware:Win32/Infoaxe,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {37 31 37 45 44 44 45 30 2d 34 34 34 46 2d 34 66 66 30 2d 42 39 43 39 2d 46 36 30 45 43 34 32 33 45 36 39 30 7d 00 } //1 ㄷ䔷䑄ぅ㐭㐴ⵆ昴て䈭䌹ⴹ㙆䔰㑃㌲㙅〹}
		$a_01_1 = {32 46 38 44 35 30 30 45 2d 34 35 34 36 2d 34 35 62 37 2d 39 32 33 36 2d 44 34 46 44 39 38 35 30 43 46 31 43 7d 00 } //1 䘲䐸〵䔰㐭㐵ⴶ㔴㝢㤭㌲ⴶ㑄䑆㠹〵䙃䌱}
		$a_03_2 = {61 64 64 74 6f 73 6f 66 74 6c 69 6e 6b 73 66 6f 72 6d 2e 6a 73 70 3f 71 3d 25 55 52 4c 25 [0-05] 41 64 64 20 74 6f 20 71 75 69 63 6b 20 6c 69 6e 6b 73 } //1
		$a_01_3 = {53 65 61 72 63 68 53 63 6f 70 65 73 5c 69 6e 66 6f 61 78 65 5f 67 6f 6f 67 6c 65 } //1 SearchScopes\infoaxe_google
		$a_01_4 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 47 6f 6f 67 6c 65 20 2b 20 49 6e 66 6f 61 78 65 } //1 楄灳慬乹浡e潇杯敬⬠䤠普慯數
		$a_01_5 = {49 00 6e 00 66 00 6f 00 61 00 78 00 65 00 5c 00 49 00 6e 00 66 00 6f 00 61 00 78 00 65 00 54 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 } //1 Infoaxe\InfoaxeToolbar
		$a_01_6 = {44 49 53 50 49 44 5f 53 41 59 48 45 4c 4c 4f 00 } //1 䥄偓䑉卟奁䕈䱌O
		$a_01_7 = {69 6e 66 6f 61 78 65 2e 63 6f 6d 2f 65 6e 68 61 6e 63 65 64 73 65 61 72 63 68 66 6f 72 6d 2e 6a 73 70 } //1 infoaxe.com/enhancedsearchform.jsp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}