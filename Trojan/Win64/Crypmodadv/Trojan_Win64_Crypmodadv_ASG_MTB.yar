
rule Trojan_Win64_Crypmodadv_ASG_MTB{
	meta:
		description = "Trojan:Win64/Crypmodadv.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 49 49 44 6f 4e 39 74 4b 62 43 63 31 6b 65 69 57 6e 4a 73 2f 5f 43 6c 4c 49 74 4d 67 48 50 64 6d 6c 6d 35 6b 41 38 77 6d 2f 77 6c 5a 39 35 6f 68 34 48 49 6d 45 37 4a 47 54 75 57 4c 59 2f 68 55 75 53 44 67 73 4b 36 63 6c 50 7a 41 43 59 36 31 7a 4b } //5 XIIDoN9tKbCc1keiWnJs/_ClLItMgHPdmlm5kA8wm/wlZ95oh4HImE7JGTuWLY/hUuSDgsK6clPzACY61zK
	condition:
		((#a_01_0  & 1)*5) >=5
 
}