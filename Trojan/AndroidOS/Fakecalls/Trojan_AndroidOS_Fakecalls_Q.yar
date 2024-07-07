
rule Trojan_AndroidOS_Fakecalls_Q{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.Q,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 61 73 74 20 43 61 6c 6c 4f 75 74 20 6e 75 6d 62 65 72 3d } //2 last CallOut number=
		$a_01_1 = {43 41 4c 4c 5f 49 4e 20 4e 75 6d 62 65 72 20 3d } //2 CALL_IN Number =
		$a_01_2 = {63 6f 6d 2e 77 72 37 32 30 32 31 30 31 32 37 33 2e 70 65 72 73 69 73 74 2e 73 73 73 } //1 com.wr7202101273.persist.sss
		$a_01_3 = {6b 77 6f 38 74 34 46 38 79 62 7a 75 2b 76 77 } //1 kwo8t4F8ybzu+vw
		$a_01_4 = {64 65 6c 65 74 65 43 6f 6e 74 61 63 74 5f 65 78 63 65 70 74 69 6f 6e } //1 deleteContact_exception
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}