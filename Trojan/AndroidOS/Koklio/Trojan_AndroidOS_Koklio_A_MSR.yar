
rule Trojan_AndroidOS_Koklio_A_MSR{
	meta:
		description = "Trojan:AndroidOS/Koklio.A!MSR,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 2e 77 33 63 34 66 2e 63 6f 6d } //1 http://w.w3c4f.com
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 2e 77 6f 63 34 62 2e 63 6f 6d } //1 http://w.woc4b.com
		$a_00_2 = {6b 6f 6b 64 64 6c 69 6f } //1 kokddlio
		$a_00_3 = {67 65 74 52 75 6e 6e 69 6e 67 54 61 73 6b 73 } //1 getRunningTasks
		$a_00_4 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 61 63 74 69 6f 6e 2e 54 49 4d 45 5f 54 49 43 4b } //1 android.intent.action.TIME_TICK
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}