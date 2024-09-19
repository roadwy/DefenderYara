
rule Trojan_MacOS_Rustbucket_AU{
	meta:
		description = "Trojan:MacOS/Rustbucket.AU,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 68 6f 77 61 72 64 2e 74 6f 6f 6c 6b 69 74 2e 63 61 6c 65 6e 64 61 72 } //1 com.howard.toolkit.calendar
		$a_00_1 = {43 55 4a 48 36 59 4b 53 51 59 } //1 CUJH6YKSQY
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}