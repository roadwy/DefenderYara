
rule Trojan_AndroidOS_SmsThief_W{
	meta:
		description = "Trojan:AndroidOS/SmsThief.W,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {35 37 37 37 39 39 30 37 32 36 42 52 49 2f 69 6e 73 74 61 6c 6c 65 64 2e 70 68 70 3f 64 65 76 3d } //2 5777990726BRI/installed.php?dev=
		$a_01_1 = {63 6f 6d 2e 6e 67 73 63 72 69 70 74 2e 73 6d 73 74 65 73 74 } //2 com.ngscript.smstest
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}