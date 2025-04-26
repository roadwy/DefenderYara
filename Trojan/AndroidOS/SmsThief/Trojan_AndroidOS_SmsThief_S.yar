
rule Trojan_AndroidOS_SmsThief_S{
	meta:
		description = "Trojan:AndroidOS/SmsThief.S,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 73 5f 66 77 64 5f 73 6d 73 } //2 is_fwd_sms
		$a_01_1 = {46 6f 72 65 67 72 6f 75 6e 64 53 65 72 76 69 63 65 43 68 61 6e 6e 65 6c 2d 43 61 6c 6c 47 69 72 6c 73 } //2 ForegroundServiceChannel-CallGirls
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}