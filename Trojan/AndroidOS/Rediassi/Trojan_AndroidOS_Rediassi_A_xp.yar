
rule Trojan_AndroidOS_Rediassi_A_xp{
	meta:
		description = "Trojan:AndroidOS/Rediassi.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 75 70 6c 6f 61 64 65 72 69 73 2e 72 75 2f } //2 ://uploaderis.ru/
		$a_01_1 = {2f 2f 62 75 74 74 6f 6e 2e 64 65 6b 65 6c 2e 72 75 2f 2e } //1 //button.dekel.ru/.
		$a_01_2 = {69 73 41 63 74 69 76 65 4e 65 74 77 6f 72 6b 4d 65 74 65 72 65 64 } //1 isActiveNetworkMetered
		$a_00_3 = {63 6f 6d 2e 72 6f 63 6b 61 73 74 61 72 2e } //1 com.rockastar.
		$a_00_4 = {4d 6f 6e 69 74 6f 72 41 63 74 69 76 69 74 79 } //1 MonitorActivity
		$a_00_5 = {6c 6f 61 64 49 6e 42 61 63 6b 67 72 6f 75 6e 64 } //1 loadInBackground
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}