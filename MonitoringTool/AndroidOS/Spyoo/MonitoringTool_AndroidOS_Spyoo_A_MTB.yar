
rule MonitoringTool_AndroidOS_Spyoo_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spyoo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {52 6f 6f 74 20 64 65 76 69 63 65 20 61 6e 64 20 61 63 63 65 70 74 20 53 75 70 65 72 20 55 73 65 72 20 66 6f 72 20 54 68 65 54 72 75 74 68 53 70 79 } //2 Root device and accept Super User for TheTruthSpy
		$a_00_1 = {4c 63 6f 6d 2f 69 73 70 79 6f 6f 2f 63 6f 6d 6d 6f 6e 2f 63 61 6c 6c 74 72 61 63 6b 65 72 2f } //2 Lcom/ispyoo/common/calltracker/
		$a_00_2 = {2f 64 61 74 61 2f 63 6f 6d 2e 77 68 61 74 73 61 70 70 2f 64 61 74 61 62 61 73 65 73 2f } //1 /data/com.whatsapp/databases/
		$a_00_3 = {2f 64 61 74 61 2f 63 6f 6d 2e 76 69 62 65 72 2e 76 6f 69 70 2f 64 61 74 61 62 61 73 65 73 2f } //1 /data/com.viber.voip/databases/
		$a_00_4 = {2f 64 61 74 61 2f 63 6f 6d 2e 66 61 63 65 62 6f 6f 6b 2e 6b 61 74 61 6e 61 2f 64 61 74 61 62 61 73 65 73 2f } //1 /data/com.facebook.katana/databases/
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}