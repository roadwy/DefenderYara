
rule Trojan_BAT_Marte_SX_MTB{
	meta:
		description = "Trojan:BAT/Marte.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 16 0d 00 00 01 6f ?? 00 00 0a 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? 00 00 0a 16 1f 0a 6f ?? 00 00 0a 13 ?? 72 ?? ?? 00 70 28 ?? 00 00 0a 13 } //20
		$a_80_1 = {7b 7b 22 47 55 49 44 22 3a 22 7b 30 7d 22 2c 22 54 79 70 65 22 3a 7b 31 7d 2c 22 4d 65 74 61 22 3a 22 7b 32 7d 22 2c 22 49 56 22 3a 22 7b 33 7d 22 2c 22 45 6e 63 72 79 70 74 65 64 4d 65 73 73 61 67 65 22 3a 22 7b 34 7d 22 2c 22 48 4d 41 43 22 3a 22 7b 35 7d 22 7d 7d } //{{"GUID":"{0}","Type":{1},"Meta":"{2}","IV":"{3}","EncryptedMessage":"{4}","HMAC":"{5}"}}  10
	condition:
		((#a_03_0  & 1)*20+(#a_80_1  & 1)*10) >=30
 
}