
rule Trojan_AndroidOS_SmsThief_R{
	meta:
		description = "Trojan:AndroidOS/SmsThief.R,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {26 74 65 78 74 3d 2a 4e 65 77 20 53 4d 53 20 52 65 63 65 69 76 65 64 2a 20 25 30 41 25 30 41 2a 53 65 6e 64 65 72 } //2 &text=*New SMS Received* %0A%0A*Sender
		$a_01_1 = {25 30 41 25 30 41 2a 54 79 70 65 20 50 65 72 61 6e 67 6b 61 74 } //2 %0A%0A*Type Perangkat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}