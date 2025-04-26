
rule Trojan_AndroidOS_SmsThief_VA{
	meta:
		description = "Trojan:AndroidOS/SmsThief.VA,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 61 79 2f 72 65 63 69 76 65 2e 70 68 70 3f 70 68 6f 6e 65 3d } //2 pay/recive.php?phone=
		$a_01_1 = {31 31 36 2e 32 30 32 2e 32 35 35 2e 31 30 30 2f 61 64 64 } //2 116.202.255.100/add
		$a_01_2 = {69 72 2f 73 69 71 65 2f 68 6f 6c 6f 2f 63 6f 6e 6e 65 63 74 } //2 ir/siqe/holo/connect
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}