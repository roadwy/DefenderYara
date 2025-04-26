
rule HackTool_AndroidOS_Whapsni_A_MTB{
	meta:
		description = "HackTool:AndroidOS/Whapsni.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 68 61 74 73 61 70 70 2e 73 6e 69 66 66 65 72 2e 55 50 44 41 54 45 5f 55 49 5f 43 4f 4e 56 45 52 53 41 43 49 4f 4e } //1 whatsapp.sniffer.UPDATE_UI_CONVERSACION
		$a_01_1 = {57 68 61 74 73 41 70 70 53 6e 69 66 66 65 72 20 53 54 41 52 54 20 53 50 4f 4f 46 49 4e 47 } //1 WhatsAppSniffer START SPOOFING
		$a_00_2 = {6b 69 6c 6c 61 6c 6c 20 61 72 70 73 70 6f 6f 66 } //1 killall arpspoof
		$a_00_3 = {53 6e 69 66 66 65 72 20 64 65 62 75 67 20 69 6e 66 6f } //1 Sniffer debug info
		$a_03_4 = {4c 63 6f 6d 2f 77 68 61 74 73 61 70 70 2f 73 6e 69 66 66 65 72 [0-10] 73 65 72 76 69 63 65 73 2f 41 72 70 73 70 6f 6f 66 53 65 72 76 69 63 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}