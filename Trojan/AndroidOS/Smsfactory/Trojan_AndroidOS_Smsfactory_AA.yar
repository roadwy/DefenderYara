
rule Trojan_AndroidOS_Smsfactory_AA{
	meta:
		description = "Trojan:AndroidOS/Smsfactory.AA,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {24 74 68 69 73 24 68 69 64 65 41 70 70 49 63 6f 6e } //01 00  $this$hideAppIcon
		$a_00_1 = {45 6e 64 6c 65 73 73 53 65 72 76 69 63 65 3a 3a 6c 6f 63 6b } //01 00  EndlessService::lock
		$a_00_2 = {24 74 68 69 73 24 67 65 74 49 6e 73 74 61 6c 6c 44 61 74 65 } //01 00  $this$getInstallDate
		$a_00_3 = {53 6d 73 53 65 6e 74 52 65 63 65 69 76 65 72 50 72 6f 78 79 } //01 00  SmsSentReceiverProxy
		$a_00_4 = {24 74 68 69 73 24 69 73 43 61 6c 6c 53 74 61 74 65 49 64 6c 65 } //00 00  $this$isCallStateIdle
	condition:
		any of ($a_*)
 
}