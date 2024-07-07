
rule TrojanDownloader_BAT_Pstinb_T_bit{
	meta:
		description = "TrojanDownloader:BAT/Pstinb.T!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 90 02 20 4c 00 6f 00 61 00 64 00 90 02 04 45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 90 00 } //2
		$a_01_1 = {52 65 76 65 72 73 65 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 敒敶獲e潃癮牥t牆浯慂敳㐶瑓楲杮
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}