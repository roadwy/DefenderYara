
rule TrojanDownloader_BAT_Pstinb_V_bit{
	meta:
		description = "TrojanDownloader:BAT/Pstinb.V!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4a 00 56 00 55 00 46 00 46 00 46 00 4f 00 54 00 46 00 48 00 41 00 47 00 4c 00 4e 00 51 00 59 00 45 00 51 00 46 00 4e 00 59 00 41 00 57 00 50 00 49 00 4a 00 } //1 JVUFFFOTFHAGLNQYEQFNYAWPIJ
		$a_01_1 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 00 54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1
		$a_01_2 = {45 6e 74 72 79 50 6f 69 6e 74 00 54 68 72 65 61 64 53 74 61 72 74 } //1 湅牴偹楯瑮吀牨慥卤慴瑲
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}