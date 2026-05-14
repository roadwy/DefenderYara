
rule Trojan_Linux_Mirai_HAQ_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 72 6f 6f 74 2f 63 6e 63 2f 62 6f 74 2f 63 2e 67 6f } //20 /root/cnc/bot/c.go
		$a_01_1 = {72 75 6e 74 69 6d 65 2e 6d 61 69 6e 2e 66 75 6e 63 32 } //2 runtime.main.func2
		$a_01_2 = {67 6f 4c 6f 6f 6b 75 70 49 50 } //3 goLookupIP
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=25
 
}