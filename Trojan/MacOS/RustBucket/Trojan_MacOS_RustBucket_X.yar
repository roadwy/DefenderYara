
rule Trojan_MacOS_RustBucket_X{
	meta:
		description = "Trojan:MacOS/RustBucket.X,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f 2e 70 6c 64 } //3 /Users/Shared/.pld
		$a_00_1 = {70 69 64 2c 75 73 65 72 2c 70 70 69 64 2c 73 74 61 72 74 2c 63 6f 6d 6d } //1 pid,user,ppid,start,comm
		$a_00_2 = {6b 65 72 6e 2e 62 6f 6f 74 74 69 6d 65 } //1 kern.boottime
		$a_00_3 = {2f 76 61 72 2f 6c 6f 67 2f 69 6e 73 74 61 6c 6c 2e 6c 6f 67 } //1 /var/log/install.log
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}