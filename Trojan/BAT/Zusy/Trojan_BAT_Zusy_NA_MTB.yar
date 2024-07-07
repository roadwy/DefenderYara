
rule Trojan_BAT_Zusy_NA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 76 65 67 61 78 2e 67 67 2f 77 69 6e 64 6f 77 73 2f 75 69 5f 76 65 72 2e 70 68 70 } ////vegax.gg/windows/ui_ver.php  5
		$a_80_1 = {56 65 67 61 58 5c 56 65 67 61 58 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 56 65 67 61 20 58 2e 70 64 62 } //VegaX\VegaX\obj\Release\Vega X.pdb  1
		$a_80_2 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 56 65 67 61 58 } //HKEY_CURRENT_USER\Software\VegaX  1
		$a_80_3 = {2f 56 65 67 61 20 58 3b 63 6f 6d 70 6f 6e 65 6e 74 2f 73 70 61 77 6e 61 62 6c 65 77 69 6e 64 6f 77 73 2f 69 6e 6a 65 63 74 63 6f 64 65 2e 78 61 6d 6c } ///Vega X;component/spawnablewindows/injectcode.xaml  1
		$a_80_4 = {61 75 74 6f 65 78 65 63 5c 76 65 67 61 78 66 70 73 75 6e 6c 6f 63 6b 65 72 2e 74 78 74 } //autoexec\vegaxfpsunlocker.txt  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=9
 
}