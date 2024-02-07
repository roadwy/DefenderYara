
rule TrojanSpy_AndroidOS_InfoStealer_SB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.SB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {71 72 63 6f 64 65 2f 62 61 63 6b 2f 6e 65 77 63 78 78 } //01 00  qrcode/back/newcxx
		$a_00_1 = {71 75 69 74 61 64 6f 70 6f 72 72 61 } //01 00  quitadoporra
		$a_00_2 = {43 6f 6e 65 78 61 6f 43 65 6e 74 72 61 6c 2e 70 68 70 } //01 00  ConexaoCentral.php
		$a_00_3 = {2f 54 65 6c 65 70 68 6f 6e 79 49 6e 66 6f } //00 00  /TelephonyInfo
	condition:
		any of ($a_*)
 
}