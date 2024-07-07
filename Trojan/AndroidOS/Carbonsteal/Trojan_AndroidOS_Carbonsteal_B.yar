
rule Trojan_AndroidOS_Carbonsteal_B{
	meta:
		description = "Trojan:AndroidOS/Carbonsteal.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 68 6d 6f 64 20 37 37 37 20 2f 73 79 73 74 65 6d 2f 61 70 70 2f 47 6f 6f 67 6c 65 4d 61 69 6c 2e 61 70 6b } //2 chmod 777 /system/app/GoogleMail.apk
		$a_00_1 = {41 6b 34 37 67 64 72 65 72 74 68 } //2 Ak47gdrerth
		$a_00_2 = {2f 61 69 6e 66 6f 64 62 2e 64 62 } //2 /ainfodb.db
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}