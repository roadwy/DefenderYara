
rule TrojanClicker_BAT_Doviali_A{
	meta:
		description = "TrojanClicker:BAT/Doviali.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 56 6f 69 44 5c } //1 C:\Users\VoiD\
		$a_01_1 = {5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 41 66 66 69 6c 69 61 74 65 44 4c 65 72 2e 70 64 62 } //1 \obj\Release\AffiliateDLer.pdb
		$a_01_2 = {77 00 77 00 77 00 2e 00 7a 00 77 00 69 00 6e 00 6b 00 79 00 2e 00 63 00 6f 00 6d 00 } //1 www.zwinky.com
		$a_01_3 = {41 00 66 00 66 00 69 00 6c 00 69 00 61 00 74 00 65 00 44 00 4c 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 AffiliateDLer.Properties.Resources
		$a_01_4 = {2f 00 63 00 6c 00 69 00 63 00 6b 00 73 00 2f 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 2f 00 61 00 63 00 74 00 69 00 76 00 65 00 5f 00 78 00 2f 00 } //1 /clicks/settings/active_x/
		$a_01_5 = {2f 00 63 00 6c 00 69 00 63 00 6b 00 73 00 2f 00 73 00 70 00 6c 00 61 00 73 00 68 00 2f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 5f 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } //1 /clicks/splash/cookie_enabled
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}