
rule Trojan_AndroidOS_Glodegl_A{
	meta:
		description = "Trojan:AndroidOS/Glodegl.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 68 6d 6f 64 20 2d 52 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 67 74 6f 6d 61 74 6f 2e 74 61 6c 6b 62 6f 78 } //1 chmod -R 777 /data/data/com.gtomato.talkbox
		$a_01_1 = {41 6d 62 69 65 6e 63 65 52 65 63 6f 72 64 46 69 6c 65 4e 61 6d 65 } //1 AmbienceRecordFileName
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}