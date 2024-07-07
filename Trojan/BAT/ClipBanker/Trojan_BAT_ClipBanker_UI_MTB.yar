
rule Trojan_BAT_ClipBanker_UI_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.UI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 6f 70 79 72 69 67 68 74 20 4c 69 6d 65 72 42 6f 79 } //1 Copyright LimerBoy
		$a_81_1 = {24 39 64 65 62 64 39 39 65 2d 32 62 36 36 2d 34 37 62 36 2d 61 33 32 37 2d 33 36 63 37 37 37 65 33 38 30 65 66 } //1 $9debd99e-2b66-47b6-a327-36c777e380ef
		$a_81_2 = {43 6c 69 70 70 65 72 2e 65 78 65 } //1 Clipper.exe
		$a_81_3 = {43 6c 69 70 62 6f 61 72 64 } //1 Clipboard
		$a_81_4 = {67 65 74 5f 4c 6f 63 61 74 69 6f 6e } //1 get_Location
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}