
rule Trojan_AndroidOS_SmsThief_V{
	meta:
		description = "Trojan:AndroidOS/SmsThief.V,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 61 63 74 69 6f 6e 3d 73 6d 73 26 6e 65 74 77 6f 72 6b 3d } //2 &action=sms&network=
		$a_01_1 = {2f 75 70 5f 66 69 6c 65 2e 70 68 70 3f 72 65 73 70 6f 6e 73 65 3d 74 72 75 65 26 69 64 3d } //2 /up_file.php?response=true&id=
		$a_01_2 = {26 61 63 63 73 65 72 76 69 63 65 3d 65 6d 70 69 74 79 26 70 6f 72 74 3d } //2 &accservice=empity&port=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}