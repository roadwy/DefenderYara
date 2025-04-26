
rule TrojanSpy_AndroidOS_Emasol_A{
	meta:
		description = "TrojanSpy:AndroidOS/Emasol.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 69 64 5f 61 73 73 65 74 2f 69 6e 64 65 78 2e 68 74 6d 6c } //1 android_asset/index.html
		$a_01_1 = {61 70 70 2d 72 6f 69 64 2e 63 6f 6d 2f 61 70 70 2f 72 76 2e 70 68 70 3f 69 64 3d } //1 app-roid.com/app/rv.php?id=
		$a_01_2 = {6d 61 69 6c 61 64 64 72 65 73 73 20 67 65 74 21 } //1 mailaddress get!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}