
rule TrojanSpy_AndroidOS_Noino_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Noino.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {41 6e 64 72 6f 69 64 55 69 53 65 72 76 69 63 65 2e 61 70 6b } //1 AndroidUiService.apk
		$a_00_1 = {67 65 74 5f 6f 6e 69 6f 6e 5f 62 6f 6e 75 73 5f 75 72 6c } //1 get_onion_bonus_url
		$a_00_2 = {6c 61 73 74 5f 73 6d 73 5f 70 69 6e 5f 74 69 6d 65 } //1 last_sms_pin_time
		$a_00_3 = {2c 6f 6e 69 6f 6e 6d 6f 62 69 73 68 61 72 65 2e 61 63 74 69 6f 6e 5f 6f 66 66 6c 69 6e 65 5f 73 74 61 72 74 5f 64 6f 77 6e 6c 6f 61 64 } //1 ,onionmobishare.action_offline_start_download
		$a_00_4 = {27 6f 6e 69 6f 6e 6d 6f 62 69 73 68 61 72 65 2e 6b 69 74 2e 63 6c 69 63 6b 2e 66 69 6e 69 73 68 2e 69 6e 73 74 61 6c 6c } //1 'onionmobishare.kit.click.finish.install
		$a_00_5 = {63 6f 6d 2e 6b 70 74 2e 78 70 6c 6f 72 65 65 2e 61 70 70 2e 64 65 6d 6f } //1 com.kpt.xploree.app.demo
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}