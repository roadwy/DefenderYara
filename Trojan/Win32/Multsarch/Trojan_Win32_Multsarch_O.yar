
rule Trojan_Win32_Multsarch_O{
	meta:
		description = "Trojan:Win32/Multsarch.O,SIGNATURE_TYPE_PEHSTR,66 00 66 00 06 00 00 "
		
	strings :
		$a_01_0 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72 } //100 㜷⌧ጝ㤤潮煰牲牲牲瑳杞幵甤敨牴牲牲
		$a_01_1 = {73 6d 73 5f 66 72 6f 6d 5f 73 6f 66 74 2e 70 68 70 } //1 sms_from_soft.php
		$a_01_2 = {31 6f 6e 5f 73 6d 73 39 31 31 5f 63 6c 69 63 6b 65 64 } //1 1on_sms911_clicked
		$a_01_3 = {7a 61 6b 2d 68 6f 73 74 2e 63 6f 6d 2f 66 75 6e } //1 zak-host.com/fun
		$a_01_4 = {47 00 73 00 6d 00 73 00 5f 00 74 00 65 00 78 00 74 00 5f 00 6e 00 75 00 6d 00 2e 00 70 00 6e 00 67 00 } //1 Gsms_text_num.png
		$a_01_5 = {73 74 69 6d 75 6c 70 72 6f 66 69 74 2e 63 6f 6d } //1 stimulprofit.com
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=102
 
}