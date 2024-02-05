
rule Trojan_BAT_Tinuke_GA_MTB{
	meta:
		description = "Trojan:BAT/Tinuke.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {2d 2d 6e 6f 2d 73 61 6e 64 62 6f 78 20 2d 2d 61 6c 6c 6f 77 2d 6e 6f 2d 73 61 6e 64 62 6f 78 2d 6a 6f 62 20 2d 2d 64 69 73 61 62 6c 65 2d 33 64 2d 61 70 69 73 20 2d 2d 64 69 73 61 62 6c 65 2d 67 70 75 20 2d 2d 64 69 73 61 62 6c 65 2d 64 33 64 31 31 20 2d 2d 75 73 65 72 2d 64 61 74 61 2d 64 69 72 3d } //--no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir=  01 00 
		$a_80_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 } //cmd.exe /c start  01 00 
		$a_80_2 = {2d 6e 6f 2d 72 65 6d 6f 74 65 20 2d 70 72 6f 66 69 6c 65 } //-no-remote -profile  01 00 
		$a_80_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 73 68 65 6c 6c 33 32 2e 64 6c 6c } //rundll32.exe shell32.dll  01 00 
		$a_80_4 = {49 73 52 65 6c 61 74 69 76 65 3d } //IsRelative=  01 00 
		$a_80_5 = {68 74 74 70 3a 2f 2f } //http://  00 00 
	condition:
		any of ($a_*)
 
}